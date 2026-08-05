-- ============================================================================
-- V10__create_partition_management.sql
-- ============================================================================

CREATE OR REPLACE PROCEDURE create_month_partition(
    partition_start DATE
)
LANGUAGE plpgsql
AS
$$
DECLARE

partition_end DATE;

    partition_name TEXT;

BEGIN

    partition_end := (partition_start + INTERVAL '1 month')::DATE;

    partition_name :=
            'audit_logs_' ||
            to_char(partition_start,'YYYY_MM');

EXECUTE format(
        '
        CREATE TABLE IF NOT EXISTS %I
        PARTITION OF audit_logs
        FOR VALUES FROM (%L) TO (%L)
        ',
        partition_name,
        partition_start,
        partition_end
    );

END;
$$;



CREATE OR REPLACE PROCEDURE ensure_future_partitions(
    months_ahead INTEGER
)
LANGUAGE plpgsql
AS
$$
DECLARE

i INTEGER;

    month_start DATE;

BEGIN

FOR i IN 0..months_ahead LOOP

            month_start :=
                    (
                        date_trunc('month', CURRENT_DATE)
                            + (i || ' month')::INTERVAL
                        )::DATE;

CALL create_month_partition(month_start);

END LOOP;

END;
$$;



CREATE OR REPLACE PROCEDURE drop_old_partitions(retention_months INTEGER)
LANGUAGE plpgsql
AS
$$
DECLARE

partition_record RECORD;

    partition_date DATE;

    cutoff DATE;

BEGIN

    cutoff :=
            (
                date_trunc('month', CURRENT_DATE)
                    - (retention_months || ' month')::INTERVAL
                )::DATE;

FOR partition_record IN

SELECT
    child.relname AS partition_name
FROM pg_inherits

         JOIN pg_class parent
              ON pg_inherits.inhparent = parent.oid

         JOIN pg_class child
              ON pg_inherits.inhrelid = child.oid

WHERE parent.relname='audit_logs'

  AND child.relname ~ '^audit_logs_[0-9]{4}_[0-9]{2}$'

        LOOP

            partition_date :=
                    to_date(
                            substring(partition_record.partition_name
                                FROM '([0-9]{4}_[0-9]{2})'),
                            'YYYY_MM'
                    );

IF partition_date < cutoff THEN

                EXECUTE format(
                        'DROP TABLE IF EXISTS %I',
                        partition_record.partition_name
                        );

END IF;

END LOOP;

END;
$$;