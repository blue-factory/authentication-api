-- +goose Up
-- +goose StatementBegin
CREATE extension if not exists pgcrypto;

create function update_updated_at_column()
returns trigger as $$
  begin
      new.updated_at = now();
      return new;
  end;
$$ language plpgsql;
-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin
drop function update_updated_at_column();
drop extension pgcrypto;
-- +goose StatementEnd
